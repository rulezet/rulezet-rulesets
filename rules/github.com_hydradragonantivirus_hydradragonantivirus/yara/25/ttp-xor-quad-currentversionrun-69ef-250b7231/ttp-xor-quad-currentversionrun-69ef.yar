rule TTP_XOR_QUAD_CurrentVersionRun_69ef {
  strings:
    $key_69ef = { 3a 80 [2] 1e 8e [2] 35 a2 [2] 1b 80 [2] 0f 9b [2] 00 81 [2] 1e 9c [2] 1c 9d [2] 07 9b [2] 1b 9c [2] 07 b3 }

  condition:
    any of them
}