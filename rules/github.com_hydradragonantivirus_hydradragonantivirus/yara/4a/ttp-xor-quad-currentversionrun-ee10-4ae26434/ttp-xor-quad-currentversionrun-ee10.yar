rule TTP_XOR_QUAD_CurrentVersionRun_ee10 {
  strings:
    $key_ee10 = { bd 7f [2] 99 71 [2] b2 5d [2] 9c 7f [2] 88 64 [2] 87 7e [2] 99 63 [2] 9b 62 [2] 80 64 [2] 9c 63 [2] 80 4c }

  condition:
    any of them
}