rule TTP_XOR_QUAD_CurrentVersionRun_c3cb {
  strings:
    $key_c3cb = { 90 a4 [2] b4 aa [2] 9f 86 [2] b1 a4 [2] a5 bf [2] aa a5 [2] b4 b8 [2] b6 b9 [2] ad bf [2] b1 b8 [2] ad 97 }

  condition:
    any of them
}