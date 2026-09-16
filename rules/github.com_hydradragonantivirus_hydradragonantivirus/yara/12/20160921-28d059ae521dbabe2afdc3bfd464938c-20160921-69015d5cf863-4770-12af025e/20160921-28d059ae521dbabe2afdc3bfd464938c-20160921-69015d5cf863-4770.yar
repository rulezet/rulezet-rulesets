rule _20160921_28d059ae521dbabe2afdc3bfd464938c_20160921_69015d5cf863_4770 {
  meta:
    description = "datamaliciousorder - from files 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash2       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash3       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"

  strings:
    $s1 = "n f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s2 = "eturn \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"BMj\";})()" ascii
    $s3 = "urn \"WIj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(f" ascii
    $s4 = "),(function f000(){return \"Ot\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Zj\";})(),(function f000(){" ascii
    $s5 = "})(),(function f000(){return \"Go\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"TRc\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}