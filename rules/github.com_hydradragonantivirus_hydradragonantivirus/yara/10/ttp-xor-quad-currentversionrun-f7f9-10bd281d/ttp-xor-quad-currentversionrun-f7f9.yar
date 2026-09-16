rule TTP_XOR_QUAD_CurrentVersionRun_f7f9 {
  strings:
    $key_f7f9 = { a4 96 [2] 80 98 [2] ab b4 [2] 85 96 [2] 91 8d [2] 9e 97 [2] 80 8a [2] 82 8b [2] 99 8d [2] 85 8a [2] 99 a5 }

  condition:
    any of them
}