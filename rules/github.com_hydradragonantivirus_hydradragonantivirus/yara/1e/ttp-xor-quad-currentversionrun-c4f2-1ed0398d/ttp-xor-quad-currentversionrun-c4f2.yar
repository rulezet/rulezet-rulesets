rule TTP_XOR_QUAD_CurrentVersionRun_c4f2 {
  strings:
    $key_c4f2 = { 97 9d [2] b3 93 [2] 98 bf [2] b6 9d [2] a2 86 [2] ad 9c [2] b3 81 [2] b1 80 [2] aa 86 [2] b6 81 [2] aa ae }

  condition:
    any of them
}