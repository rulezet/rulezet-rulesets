rule TTP_XOR_QUAD_CurrentVersionRun_ee2d {
  strings:
    $key_ee2d = { bd 42 [2] 99 4c [2] b2 60 [2] 9c 42 [2] 88 59 [2] 87 43 [2] 99 5e [2] 9b 5f [2] 80 59 [2] 9c 5e [2] 80 71 }

  condition:
    any of them
}