rule TTP_XOR_QUAD_CurrentVersionRun_c412 {
  strings:
    $key_c412 = { 97 7d [2] b3 73 [2] 98 5f [2] b6 7d [2] a2 66 [2] ad 7c [2] b3 61 [2] b1 60 [2] aa 66 [2] b6 61 [2] aa 4e }

  condition:
    any of them
}