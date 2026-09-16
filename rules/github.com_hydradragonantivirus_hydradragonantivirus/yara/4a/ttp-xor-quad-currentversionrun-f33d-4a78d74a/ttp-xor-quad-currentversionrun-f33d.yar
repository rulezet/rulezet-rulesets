rule TTP_XOR_QUAD_CurrentVersionRun_f33d {
  strings:
    $key_f33d = { a0 52 [2] 84 5c [2] af 70 [2] 81 52 [2] 95 49 [2] 9a 53 [2] 84 4e [2] 86 4f [2] 9d 49 [2] 81 4e [2] 9d 61 }

  condition:
    any of them
}