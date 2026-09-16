rule TTP_XOR_QUAD_CurrentVersionRun_f92f {
  strings:
    $key_f92f = { aa 40 [2] 8e 4e [2] a5 62 [2] 8b 40 [2] 9f 5b [2] 90 41 [2] 8e 5c [2] 8c 5d [2] 97 5b [2] 8b 5c [2] 97 73 }

  condition:
    any of them
}