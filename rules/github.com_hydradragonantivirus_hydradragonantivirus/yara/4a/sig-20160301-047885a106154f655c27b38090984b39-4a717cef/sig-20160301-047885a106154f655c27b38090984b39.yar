rule sig_20160301_047885a106154f655c27b38090984b39 {
  meta:
    description = "datamaliciousorder - file 20160301_047885a106154f655c27b38090984b39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1604970bfb28ed4e089fec791e6ded56b859715c17ea7b02a54e7daa3c772a4c"

  strings:
    $s1 = "dessertAbsurd = marchTerror[(\"indifferent\", \"accumulator\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"boxing\", \"pa" ascii
    $s2 = "dessertAbsurd = marchTerror[(\"indifferent\", \"accumulator\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"boxing\", \"pa" ascii
    $s3 = "while(saluteCompress[(\"readystate\")] < ((156 / 39))) {" fullword ascii
    $s4 = "dialectRadical = ((((((([!+[] + !+[]])) + \"\" + (([!+[] + !+[] + !+[]])))) * ([!+[] + !+[]])) + (56, 28, 237, 55)), this);" fullword ascii
    $s5 = "} catch(firmReputation) {};" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    all of them
}