rule TTP_XOR_QUAD_CurrentVersionRun_ee0a {
  strings:
    $key_ee0a = { bd 65 [2] 99 6b [2] b2 47 [2] 9c 65 [2] 88 7e [2] 87 64 [2] 99 79 [2] 9b 78 [2] 80 7e [2] 9c 79 [2] 80 56 }

  condition:
    any of them
}