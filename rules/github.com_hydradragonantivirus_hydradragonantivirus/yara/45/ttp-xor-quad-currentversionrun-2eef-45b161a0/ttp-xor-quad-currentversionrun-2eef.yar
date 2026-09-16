rule TTP_XOR_QUAD_CurrentVersionRun_2eef {
  strings:
    $key_2eef = { 7d 80 [2] 59 8e [2] 72 a2 [2] 5c 80 [2] 48 9b [2] 47 81 [2] 59 9c [2] 5b 9d [2] 40 9b [2] 5c 9c [2] 40 b3 }

  condition:
    any of them
}