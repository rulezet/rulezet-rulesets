rule TTP_XOR_QUAD_CurrentVersionRun_f13d {
  strings:
    $key_f13d = { a2 52 [2] 86 5c [2] ad 70 [2] 83 52 [2] 97 49 [2] 98 53 [2] 86 4e [2] 84 4f [2] 9f 49 [2] 83 4e [2] 9f 61 }

  condition:
    any of them
}