rule sig_20160301_a01127248485498ed3839d3199868fcf {
  meta:
    description = "datamaliciousorder - file 20160301_a01127248485498ed3839d3199868fcf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e7bc4395d3ce3c267e3f0920a87afeb6a50762d18ba108c26dc0cae225e7724"

  strings:
    $s1 = "\"nv\\u0069\" + \"ro\" + \"n\" + \"\\u006den\\u0074\\u0053\\u0074\" + \"ri\\u006e\" + \"\\u0067\\u0073\")]((\"f\\u0061\\u0074a" ascii
    $s2 = "  toxicAccommodation[(\"ma\\u006e\\u0064\" + \"\\u0061\\u0074\\u0065\", function String.prototype.modernOperation() {" fullword ascii
    $s3 = "while (demonMotor[(\"\\u006cice\" + \"nce\", \"\\u0061\" + \"\\u0072b\" + \"i\\u0074er\", \"\\u0072\\u0065\" + \"\\u0061\\u0064" ascii
    $s4 = "while (demonMotor[(\"\\u006cice\" + \"nce\", \"\\u0061\" + \"\\u0072b\" + \"i\\u0074er\", \"\\u0072\\u0065\" + \"\\u0061\\u0064" ascii
    $s5 = "butterflyAvenue = ((18 / 18), this);" fullword ascii
    $s6 = "} catch (administrationFormula) {};" fullword ascii

  condition:
    uint16(0) == 0x7562 and
    all of them
}