rule sig_20151129_0c273d4bf5ebf3d6fa8bcbb467bb3b26 {
  meta:
    description = "datamaliciousorder - file 20151129_0c273d4bf5ebf3d6fa8bcbb467bb3b26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cd73370154084cd7fe642363729327199cf339ea24f068bbb3be4e6b451afbd"

  strings:
    $s1 = "function N(wmeWEUfvIG,TIiMDFuLPQ,VTosougVZo){return String.fromCharCode(wmeWEUfvIG)+String.fromCharCode(TIiMDFuLPQ)+String.fromC" ascii
    $s2 = "function N(wmeWEUfvIG,TIiMDFuLPQ,VTosougVZo){return String.fromCharCode(wmeWEUfvIG)+String.fromCharCode(TIiMDFuLPQ)+String.fromC" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}