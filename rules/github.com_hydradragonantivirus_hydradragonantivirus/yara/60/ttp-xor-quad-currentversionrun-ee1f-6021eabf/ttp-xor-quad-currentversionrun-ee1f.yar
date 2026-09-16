rule TTP_XOR_QUAD_CurrentVersionRun_ee1f {
  strings:
    $key_ee1f = { bd 70 [2] 99 7e [2] b2 52 [2] 9c 70 [2] 88 6b [2] 87 71 [2] 99 6c [2] 9b 6d [2] 80 6b [2] 9c 6c [2] 80 43 }

  condition:
    any of them
}