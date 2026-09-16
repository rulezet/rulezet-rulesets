rule TTP_XOR_QUAD_CurrentVersionRun_2433 {
  strings:
    $key_2433 = { 77 5c [2] 53 52 [2] 78 7e [2] 56 5c [2] 42 47 [2] 4d 5d [2] 53 40 [2] 51 41 [2] 4a 47 [2] 56 40 [2] 4a 6f }

  condition:
    any of them
}