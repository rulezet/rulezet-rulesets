rule _20160921_28d059ae521dbabe2afdc3bfd464938c_20160921_85b0b9490091_4768 {
  meta:
    description = "datamaliciousorder - from files 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160921_85b0b94900915170fd854268d8d17fd4.js, 20160921_a864250b4ae6162ed0d7a2f3ed785d46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash2       = "02801a1fe1d3c30ef8c10eab40eabc26c88f8bc28e76e3aecbbb89d0981b21af"
    hash3       = "f64f9f9fd1a5e4b096281bd9733f52c453683cc9032801264dd73f202b17964f"

  strings:
    $s1 = "\"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(funct" ascii
    $s2 = "})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(function f000" ascii
    $s3 = "),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){r" ascii
    $s4 = "(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(" ascii
    $s5 = "urn \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}