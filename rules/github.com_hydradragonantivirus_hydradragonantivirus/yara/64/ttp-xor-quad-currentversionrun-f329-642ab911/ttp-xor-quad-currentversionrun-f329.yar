rule TTP_XOR_QUAD_CurrentVersionRun_f329 {
  strings:
    $key_f329 = { a0 46 [2] 84 48 [2] af 64 [2] 81 46 [2] 95 5d [2] 9a 47 [2] 84 5a [2] 86 5b [2] 9d 5d [2] 81 5a [2] 9d 75 }

  condition:
    any of them
}