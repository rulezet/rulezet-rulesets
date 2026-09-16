rule TTP_XOR_QUAD_CurrentVersionRun_f112 {
  strings:
    $key_f112 = { a2 7d [2] 86 73 [2] ad 5f [2] 83 7d [2] 97 66 [2] 98 7c [2] 86 61 [2] 84 60 [2] 9f 66 [2] 83 61 [2] 9f 4e }

  condition:
    any of them
}