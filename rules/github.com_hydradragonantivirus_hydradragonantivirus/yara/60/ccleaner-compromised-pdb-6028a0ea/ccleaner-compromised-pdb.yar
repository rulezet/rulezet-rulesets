rule ccleaner_compromised_pdb {
    meta:
      author = "NVISIO"
      reference = "https://blog.nviso.be/2017/09/21/yara-rules-for-ccleaner-5-33/"
    strings:
        $a = "s:\\workspace\\ccleaner\\branches\\v5.33\\bin\\CCleaner\\Release\\CCleaner.pdb" 
        $b = "s:\\workspace\\ccleaner\\branches\\v5.33\\bin\\CCleaner\\ReleaseTV\\CCleaner.pdb" 
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and ($a or $b)
}