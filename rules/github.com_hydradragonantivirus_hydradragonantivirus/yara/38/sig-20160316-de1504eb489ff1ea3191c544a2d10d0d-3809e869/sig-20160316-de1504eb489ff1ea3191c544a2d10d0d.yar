rule sig_20160316_de1504eb489ff1ea3191c544a2d10d0d {
  meta:
    description = "datamaliciousorder - file 20160316_de1504eb489ff1ea3191c544a2d10d0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0849bfc1b0b54e5981049d65f326b09f3c3261a99ef8d0d0a4a1ca1ab8d5a073"

  strings:
    $s1  = "wroufx = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s2  = "do ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "xBQmng.onreadystatechange = function () {" fullword ascii
    $s4  = "whisk = ((\"adverse\", \"singh\", \"WbaIft\", \"simpson\", \"pQvNMylyHok\") + \"UhEMeTqIJm\").conservatory();" fullword ascii
    $s5  = "    MCNvwirzx[IafdWuQPS[faultlessI+1]](MrkIv, 1, \"SxtyzSz\" === \"UCCRlUeJa\"); VaGtEDG = \" \\\"PSEUDO\\\": function( pseudo, " ascii
    $s6  = "wroufx = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s7  = "String.prototype.conservatory = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = "DqUWMpf = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s9  = "OUGTKS = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = ") { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case " ascii
    $s11 = "FWxHBXvnpK = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s12 = "FWxHBXvnpK = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s13 = "ence\",\"S\"), \"ebWBtRt\", \"h\"+\"ma\"+(\"slightly\",\"ingredient\",\"leisure\",\"inducement\",\"rrowel\")+(\"basket\",\"gauzy" ascii
    $s14 = "var fmTpyjlR = this[pills];" fullword ascii
    $s15 = "\"clove\",\"neutral\",\"/v\")+\"4v\"+\"5g\"+\"45\"+\"hg\"+\".e\"+(\"rivers\",\"nomadic\",\"scoop\",\"clayey\",\"xe\"), false);" fullword ascii
    $s16 = "sSztYq = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s17 = "sSztYq = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s18 = "        kHImjsPLBQ = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii
    $s19 = "        NMDcAICgXC = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { " ascii
    $s20 = "    xBQmng.open(\"G\"+(\"serial\",\"pellucid\",\"enrolled\",\"ET\"), \"h\"+(\"scope\",\"strategic\",\"asian\",\"clustered\",\"tt" ascii

  condition:
    uint16(0) == 0x4276 and
    8 of them
}