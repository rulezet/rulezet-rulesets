rule TTP_XOR_QUAD_CurrentVersionRun_2bee {
  strings:
    $key_2bee = { 78 81 [2] 5c 8f [2] 77 a3 [2] 59 81 [2] 4d 9a [2] 42 80 [2] 5c 9d [2] 5e 9c [2] 45 9a [2] 59 9d [2] 45 b2 }

  condition:
    any of them
}