rule TTP_XOR_QUAD_CurrentVersionRun_2bed {
  strings:
    $key_2bed = { 78 82 [2] 5c 8c [2] 77 a0 [2] 59 82 [2] 4d 99 [2] 42 83 [2] 5c 9e [2] 5e 9f [2] 45 99 [2] 59 9e [2] 45 b1 }

  condition:
    any of them
}