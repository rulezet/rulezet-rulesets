rule TTP_XOR_QUAD_CurrentVersionRun_ee21 {
  strings:
    $key_ee21 = { bd 4e [2] 99 40 [2] b2 6c [2] 9c 4e [2] 88 55 [2] 87 4f [2] 99 52 [2] 9b 53 [2] 80 55 [2] 9c 52 [2] 80 7d }

  condition:
    any of them
}