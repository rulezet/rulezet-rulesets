rule sig_20160301_ff342057fb21f723dc43c57251139f47 {
  meta:
    description = "datamaliciousorder - file 20160301_ff342057fb21f723dc43c57251139f47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29d2d991b1192d3dbd5d5fc2eef05be73e6239daa529c8b7e85609ea751a0a35"

  strings:
    $s1 = "violetActor = telephonePassive[(\"v\" + \"oya\" + \"g\" + \"e\", \"tech\" + \"niq\" + \"ue\", \"a\" + \"sso\" + \"ciatio\" + \"n" ascii
    $s2 = "while (princeAntenna[(\"su\" + \"bsta\" + \"nce\", \"rh\" + \"o\" + \"mb\" + \"us\", \"read\" + \"ystate\")] < (([!+[] + !+[]]) " ascii
    $s3 = "while (princeAntenna[(\"su\" + \"bsta\" + \"nce\", \"rh\" + \"o\" + \"mb\" + \"us\", \"read\" + \"ystate\")] < (([!+[] + !+[]]) " ascii
    $s4 = "\"quaran\" + \"ti\" + \"n\" + \"e\", function String.prototype.unisonPerspective() {" fullword ascii
    $s5 = "telephonePassive = ((1), this);" fullword ascii
    $s6 = "} catch (duplicateSpeculation) {};" fullword ascii

  condition:
    uint16(0) == 0x6574 and
    all of them
}