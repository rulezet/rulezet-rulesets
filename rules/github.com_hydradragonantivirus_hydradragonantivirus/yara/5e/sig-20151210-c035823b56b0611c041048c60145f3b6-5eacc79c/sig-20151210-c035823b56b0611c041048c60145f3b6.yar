rule sig_20151210_c035823b56b0611c041048c60145f3b6 {
  meta:
    description = "datamaliciousorder - file 20151210_c035823b56b0611c041048c60145f3b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97b2e7db6ede9458d3991666c4c7ec7d8061a8b096d27f53049b8d4538d53c37"

  strings:
    $s1  = "function aalvfPvQwAYQZTKOcggzFUbJsfyvTvjXTRnaBERImcliHqzbDZphJd(GbhyGaXDaBjCy,OIXPNsiQqgEtUo){ return UxqQwNMMSHzgm[RmIBB(GbhyGa" ascii
    $s2  = " ODran;}function kAYxCwHjnuZBgkX(KQNFyafFIcKDRheaD){eval(KQNFyafFIcKDRheaD)}" fullword ascii
    $s3  = "function RmIBB(pyrSnZEwkdf,ibqWuZlYcJYrN,mqQKHuQI){XkeK=parseInt(pyrSnZEwkdf,ibqWuZlYcJYrN);ODran=XkeK.toString(mqQKHuQI);return" ascii
    $s4  = "function aalvfPvQwAYQZTKOcggzFUbJsfyvTvjXTRnaBERImcliHqzbDZphJd(GbhyGaXDaBjCy,OIXPNsiQqgEtUo){ return UxqQwNMMSHzgm[RmIBB(GbhyGa" ascii
    $s5  = "function fqnsIiL(hDoPwZMjWGjQVzdWSExGvvmLPvGMkdGaUOKU) {return !isNaN(parseFloat(hDoPwZMjWGjQVzdWSExGvvmLPvGMkdGaUOKU)) && isFin" ascii
    $s6  = "function fqnsIiL(hDoPwZMjWGjQVzdWSExGvvmLPvGMkdGaUOKU) {return !isNaN(parseFloat(hDoPwZMjWGjQVzdWSExGvvmLPvGMkdGaUOKU)) && isFin" ascii
    $s7  = "function lQRHbeUdLJB(hgXeQbiC,JpaezD){return hgXeQbiC.split(JpaezD)}" fullword ascii
    $s8  = "function jHptqbPkhNZAEgOcd(HNmBZ){FeXAMFNgvou= '';for(UupRQgrYOIC=(-370+370)/819; UupRQgrYOIC < (-435+621)/93; UupRQgrYOIC++) {H" ascii
    $s9  = "function jHptqbPkhNZAEgOcd(HNmBZ){FeXAMFNgvou= '';for(UupRQgrYOIC=(-370+370)/819; UupRQgrYOIC < (-435+621)/93; UupRQgrYOIC++) {H" ascii
    $s10 = "+;}} return FeXAMFNgvou}" fullword ascii
    $s11 = "nZjqCZs=(-858+858)/958;while(true){if(nZjqCZs>=(31887+881)/256){break;}UxqQwNMMSHzgm[nZjqCZs]=String.fromCharCode(nZjqCZs);nZjqC" ascii
    $s12 = "function RmIBB(pyrSnZEwkdf,ibqWuZlYcJYrN,mqQKHuQI){XkeK=parseInt(pyrSnZEwkdf,ibqWuZlYcJYrN);ODran=XkeK.toString(mqQKHuQI);return" ascii
    $s13 = "nZjqCZs=(-858+858)/958;while(true){if(nZjqCZs>=(31887+881)/256){break;}UxqQwNMMSHzgm[nZjqCZs]=String.fromCharCode(nZjqCZs);nZjqC" ascii
    $s14 = "llnqEzzJ[UupRQgrYOIC]=(-868+868)/211; while(true) { if(HllnqEzzJ[UupRQgrYOIC] > HNmBZ[UupRQgrYOIC].length-(-784+832)/48) { break" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}