rule TTP_XOR_QUAD_CurrentVersionRun_62ef {
  strings:
    $key_62ef = { 31 80 [2] 15 8e [2] 3e a2 [2] 10 80 [2] 04 9b [2] 0b 81 [2] 15 9c [2] 17 9d [2] 0c 9b [2] 10 9c [2] 0c b3 }

  condition:
    any of them
}