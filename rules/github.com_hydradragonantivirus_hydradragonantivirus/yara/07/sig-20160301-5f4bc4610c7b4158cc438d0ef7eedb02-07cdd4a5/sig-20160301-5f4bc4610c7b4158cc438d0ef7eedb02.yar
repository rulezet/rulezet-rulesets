rule sig_20160301_5f4bc4610c7b4158cc438d0ef7eedb02 {
  meta:
    description = "datamaliciousorder - file 20160301_5f4bc4610c7b4158cc438d0ef7eedb02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "032aeebe96dacaa38530f026b647db1ebcd6b6776b73428efeed526095cd5389"

  strings:
    $s1 = "capitulationHotel = packingFlag[(\"photograph\", \"ExpandEnvironmentStrings\")]((\"initiative\", \"%TEMP%/\")) + (\"mate\", \"di" ascii
    $s2 = "while(publicationSecret[(\"readystate\")] < (Math.pow((9 | 13), 2) - (([!+[] + !+[]] * [!+[] + !+[] + !+[]] - 1) * ([!+[] + !+[]" ascii
    $s3 = "while(publicationSecret[(\"readystate\")] < (Math.pow((9 | 13), 2) - (([!+[] + !+[]] * [!+[] + !+[] + !+[]] - 1) * ([!+[] + !+[]" ascii
    $s4 = "capitulationHotel = packingFlag[(\"photograph\", \"ExpandEnvironmentStrings\")]((\"initiative\", \"%TEMP%/\")) + (\"mate\", \"di" ascii
    $s5 = "experimentPotentiality = (((247 - 115), (27 + 53)), this);" fullword ascii
    $s6 = "blankControl[(\"microphone\", \"region\", function String.prototype.bufferBoard() {" fullword ascii
    $s7 = "} catch(residentResident) {};" fullword ascii

  condition:
    uint16(0) == 0x7865 and
    all of them
}