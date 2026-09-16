rule sig_20160316_f11c62fea25cbb55974688c9fa0d22af {
  meta:
    description = "datamaliciousorder - file 20160316_f11c62fea25cbb55974688c9fa0d22af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ec01f4fba1675ec47eb076046f5abe818ab22b7ccfe1a2673e8b2a711dc32bf"

  strings:
    $s1  = "    CQByvHx[BoWCkps[reliefI+1]](vnWYmJxRD, 1, \"BhaREyIQMIP\" === \"TGmBtV\"); rKbRCmdf = \" \\\"PSEUDO\\\": function( pseudo, a" ascii
    $s2  = "QuyKQS = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s3  = ",\"encoding\",\"pedantic\",\"thank\",\"/v4v\")+(\"valley\",\"objectionable\",\"generator\",\"5g45hg\")+(\"romeo\",\"effect\",\"." ascii
    $s4  = "TsnyKhW.onreadystatechange = function () {" fullword ascii
    $s5  = "impact = ((\"tapes\", \"benjamin\", \"VOOjLNDYGo\", \"metric\", \"pqYLOkrIt\") + \"DYOjFCfIi\").codes();" fullword ascii
    $s6  = "QuyKQS = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s7  = "sKoVyucV = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s8  = "qYFyzDoYtOg = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s9  = "String.prototype.codes = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "    TsnyKhW.open(\"G\"+(\"bridget\",\"belongs\",\"ET\"), \"h\"+(\"trill\",\"expiate\",\"tt\")+(\"arbitration\",\"appearance\",\"" ascii
    $s11 = "ARftxN = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s12 = "ARftxN = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s13 = "var koDMV = this[plenary];" fullword ascii
    $s14 = "(\"vixen\",\"juvenile\",\"crossly\",\"flashers\",\"fo\")+\"rb\"+\"idde\"+(\"difficulties\",\"reproduce\",\"nelforbiddenl\"), \"n" ascii
    $s15 = "plenary = BoWCkps[2+2+2].split(\"forbidden\").join(\"\");" fullword ascii
    $s16 = "\"), \"PHehiQ\", \"vTgwlLM\", (\"perth\",\"auburn\",\"W\")+\"Sc\"+\"forb\"+\"id\"+\"de\"+(\"dross\",\"rampart\",\"nr\")+\"ip\"+" ascii
    $s17 = "        JUGfU[(\"alaric\",\"durable\",\"w\")+\"ri\"+\"te\"](TsnyKhW[(\"sentence\",\"vegetation\",\"vehicles\",\"\")+\"R\"+\"es\"" ascii
    $s18 = "RFmrdBIiisl = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID" ascii
    $s19 = "RFmrdBIiisl = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID" ascii
    $s20 = "    CQByvHx[BoWCkps[reliefI+1]](vnWYmJxRD, 1, \"BhaREyIQMIP\" === \"TGmBtV\"); rKbRCmdf = \" \\\"PSEUDO\\\": function( pseudo, a" ascii

  condition:
    uint16(0) == 0x7a63 and
    8 of them
}