rule sig_20160316_0528ee8e6cfc2957ed87408f2a26ad09 {
  meta:
    description = "datamaliciousorder - file 20160316_0528ee8e6cfc2957ed87408f2a26ad09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc0a4df7ef0b2622876509066a8c7225ee78cd99dc28ef2abcd9e3c46c6f6032"

  strings:
    $s1  = "ters\",\"te\")+\"ch\"+\"nologi\"+(\"bridget\",\"observatory\",\"brutal\",\"therapy\",\"es.com/v\")+(\"fluffy\",\"premiere\",\"4v" ascii
    $s2  = "    CqasB.open(\"G\"+(\"malachi\",\"disgorge\",\"ET\"), \"http://\"+(\"divide\",\"jackson\",\"besiege\",\"altercation\",\"winj\"" ascii
    $s3  = "CNWWUCMO = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s4  = "CqasB.onreadystatechange = function () {" fullword ascii
    $s5  = "|| Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s6  = "CNWWUCMO = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s7  = "    Lextxi[UkxDHkcNe[premiumI+1]](KcEoHoKip, 1, \"MMScDVVl\" === \"SFEsdc\"); FXjBt = \" \\\"PSEUDO\\\": function( pseudo, argum" ascii
    $s8  = "ovTloYw = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s9  = "TWMduuXsPr = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "String.prototype.joust = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "ctkfpst = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s12 = "seudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custo" ascii
    $s13 = "ctkfpst = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s14 = "admittedly = UkxDHkcNe[2+2+2].split(\"markets\").join(\"\");" fullword ascii
    $s15 = "var POnrfKX = this[admittedly];" fullword ascii
    $s16 = "SINQsFdOxC = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s17 = "SINQsFdOxC = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s18 = "        SoxUhfgK = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { un" ascii
    $s19 = "        qaDxtPztxx = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii
    $s20 = "} catch (pAQBLmpjl) { };" fullword ascii

  condition:
    uint16(0) == 0x7272 and
    8 of them
}