rule Trojan_Danger_Trojan_GenericKD_72677122_276_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_276_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6bc5567bfdd3894babbe44f524b329799caf15476f34d16e37d5832792af6a5"

  strings:
    $x1  = "  --tagtime timestamp --information \"[psst]I see metadata\" --url http://www.bumperdumper.com" fullword ascii
    $s2  = "Note: to remove the copyright, set the string to \"\" - the track and language must match the target." fullword ascii
    $s3  = "AtomicParsley error: there was an error reading the CD Table of Contents header (win32)." fullword ascii
    $s4  = "AtomicParsley error: no moov.udta atom was found to dump out to file." fullword ascii
    $s5  = " --ID3Tag APIC /path/to/img.ext desc=\"something to say\" imagetype=0x08 UTF16LE compressed" fullword ascii
    $s6  = "  --encodedBy        ,       (str)    Set the name of the Person/company who encoded the file on the \"" fullword ascii
    $s7  = "AtomicParsley error: insufficient memory to process ID3 tags (%u>%u). Exiting." fullword ascii
    $s8  = "  --encodedBy    (string)     Set the name of the Person/company who encoded the file" fullword ascii
    $s9  = "Submit bug fixes to https://github.com/wez/atomicparsley" fullword ascii
    $s10 = "      usage is \"AP --ID3Tag APIC /path.jpg --imagetype=\"str\"" fullword ascii
    $s11 = "AP error: skipping non-existing track number setting frame %s for ID32 atom." fullword ascii
    $s12 = "FILE%s; mime-type=%s; description=%s" fullword ascii
    $s13 = "%i  -  Atom \"%s\" (level %u) has next atom at #%i" fullword ascii
    $s14 = "Movie duration: %.3lf seconds (%s) - %.2lf* kbp/sec bitrate (*=approximate)" fullword ascii
    $s15 = "  -  version %u" fullword ascii
    $s16 = "AtomicParsley error: an error occurred while trying to create a temp file." fullword ascii
    $s17 = "the --DeepScan option is required for this operation. Skipping" fullword ascii
    $s18 = "  ...  Extracted uuid=pass attachment to file: /Users/me/Desktop/plops_pass_uuid.pdf" fullword ascii
    $s19 = "                        -t +    show supplemental info like free space, available padding, user data" fullword ascii
    $s20 = "  --output           ,  -o   (/path)  Specify the filename of tempfile (voids overWrite)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}