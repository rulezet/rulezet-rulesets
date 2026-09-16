rule sig_20160203_57964890896434fad996afcd5e50a13b {
  meta:
    description = "datamaliciousorder - file 20160203_57964890896434fad996afcd5e50a13b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ea76871f722e3de269fa5ed4b23354ce827e946defc8d0a729a07032e1c2c64"

  strings:
    $s1  = "', 'T'.split(\"\").reverse().join(\"\")) + '' , arguments[0], false);" fullword ascii
    $s2  = "', 'a') + 'n' + ('86', 'd6lQa', 'Ie', 'g') + 'e'] = function() {" fullword ascii
    $s3  = "verse().join(\"\")) + 'bj' + ('NqipLe', 'peiX', 'f4', 'h'.split(\"\").reverse().join(\"\")) + 'a' + ('R49', 'SZX', 'A9xGke', 'g'" ascii
    $s4  = "everse().join(\"\")) + 'P%' ) + String ['fr' + ('BZ2mvP', 'uOB5', '8TQan', 'o') + '' + ('Pyb', 'VcATf', 'p5', 'm') + 'C' + ('86U" ascii
    $s5  = "function aibvjxCVO () {" fullword ascii
    $s6  = "    a09rzAfR8['o' + ('3S', 'etJu4s', '87i2vk', 'n') + 'r' + ('Inr9Qt', 'SXqZZ', '2Rjg', 'e') + '' + ('Lp', 'EyDW', '8hl0Z', 'a')" ascii
    $s7  = "    var a09rzAfR8 = new this['A' + ('vZaPg', 'E4NQef', 'eokDr', 'c') + '' + ('A4h', '0P', 'KptqVs', 't') + 'i' + ('IppNd', '1s3'" ascii
    $s8  = "        a09rzAfR8['op' + ('sJ2J', '2v', 'ep', 'e') + '' + ('QuHyeA', 'qGnK4', 'kZXxz', 'n') + '']('GE' + ('oJsr', 'DFF', 'Bvtj3I" ascii
    $s9  = "    var agwDO9yCW = new this['Ac' + ('hDN8G', 'q6eG', 'UPqA', 't') + '' + ('zyS', 'Rv', 'M6z', 'i') + 'v' + ('lu', 'YhxE', 'YKWE" ascii
    $s10 = "    var agwDO9yCW = new this['Ac' + ('hDN8G', 'q6eG', 'UPqA', 't') + '' + ('zyS', 'Rv', 'M6z', 'i') + 'v' + ('lu', 'YhxE', 'YKWE" ascii
    $s11 = "    var a09rzAfR8 = new this['A' + ('vZaPg', 'E4NQef', 'eokDr', 'c') + '' + ('A4h', '0P', 'KptqVs', 't') + 'i' + ('IppNd', '1s3'" ascii
    $s12 = "            var aR3ChpOfp = new this['A' + ('tNOO', '3dJ', 'F3m', 'c') + '' + ('VHs', 'jOvp4S', 'eyO', 't') + '' + ('oLocz', 'fN" ascii
    $s13 = "            var aR3ChpOfp = new this['A' + ('tNOO', '3dJ', 'F3m', 'c') + '' + ('VHs', 'jOvp4S', 'eyO', 't') + '' + ('oLocz', 'fN" ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}