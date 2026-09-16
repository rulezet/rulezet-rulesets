rule TTP_XOR_QUAD_CurrentVersionRun_0bee {
  strings:
    $key_0bee = { 58 81 [2] 7c 8f [2] 57 a3 [2] 79 81 [2] 6d 9a [2] 62 80 [2] 7c 9d [2] 7e 9c [2] 65 9a [2] 79 9d [2] 65 b2 }

  condition:
    any of them
}