rule TTP_XOR_QUAD_CurrentVersionRun_ee0d {
  strings:
    $key_ee0d = { bd 62 [2] 99 6c [2] b2 40 [2] 9c 62 [2] 88 79 [2] 87 63 [2] 99 7e [2] 9b 7f [2] 80 79 [2] 9c 7e [2] 80 51 }

  condition:
    any of them
}