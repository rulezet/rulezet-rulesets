rule TTP_XOR_QUAD_CurrentVersionRun_c43a {
  strings:
    $key_c43a = { 97 55 [2] b3 5b [2] 98 77 [2] b6 55 [2] a2 4e [2] ad 54 [2] b3 49 [2] b1 48 [2] aa 4e [2] b6 49 [2] aa 66 }

  condition:
    any of them
}