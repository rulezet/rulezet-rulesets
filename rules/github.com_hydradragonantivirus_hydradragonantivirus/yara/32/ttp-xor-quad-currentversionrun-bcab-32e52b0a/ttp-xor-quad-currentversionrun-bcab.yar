rule TTP_XOR_QUAD_CurrentVersionRun_bcab {
  strings:
    $key_bcab = { ef c4 [2] cb ca [2] e0 e6 [2] ce c4 [2] da df [2] d5 c5 [2] cb d8 [2] c9 d9 [2] d2 df [2] ce d8 [2] d2 f7 }

  condition:
    any of them
}