rule sig_20160222_cf144aa5cfaa44b30481d9e91ff2408e {
  meta:
    description = "datamaliciousorder - file 20160222_cf144aa5cfaa44b30481d9e91ff2408e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca88f41db44a44de69492458fd3b8d47ecfdb43a196df9756e6a054f60d96a26"

  strings:
    $s1 = "    processInflation= Function(('registration', '\\u0072popular'.e()) + 'et' + ('proportion', 'initiative', '\\u0075budget'.e())" ascii
    $s2 = "    processInflation= Function(('registration', '\\u0072popular'.e()) + 'et' + ('proportion', 'initiative', '\\u0075budget'.e())" ascii
    $s3 = "religion', 'director', 'reorganize', '\\u0074terrace'.e()) + 'r' + ('suffix', '\\u0065terminology'.e()) + 'am');" fullword ascii
    $s4 = "itch', 'impression', 'premium', 'order', 'theorem', '\\u0053international'.e()) + 'le' + ('trophy', 'gallery', 'bus', 'transport" ascii
    $s5 = "    while (proportionOcean[('meditate', 'progress', 'expert', 'central', '\\u0072lord'.e()) + 'e' + ('prologue', 'consultant', '" ascii
    $s6 = "    while (proportionOcean[('meditate', 'progress', 'expert', 'central', '\\u0072lord'.e()) + 'e' + ('prologue', 'consultant', '" ascii
    $s7 = "regenerate', 'telephone', 'scalpel', '\\u0063territory'.e()) + 'ri' + ('inversion', 'university', 'profession', '\\u0070fact'.e(" ascii
    $s8 = ", 'coordination', '\\u0074voyage'.e()) + 'e'] != ((1|4)&(2^6))) {this[('progression', 'club', 'handicap', 'machine', 'inspection" ascii
    $s9 = "    function String.prototype.e(a) {return this.charAt(a);} " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    all of them
}