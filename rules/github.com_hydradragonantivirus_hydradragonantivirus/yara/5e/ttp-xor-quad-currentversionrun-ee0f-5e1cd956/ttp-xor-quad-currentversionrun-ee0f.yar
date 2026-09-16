rule TTP_XOR_QUAD_CurrentVersionRun_ee0f {
  strings:
    $key_ee0f = { bd 60 [2] 99 6e [2] b2 42 [2] 9c 60 [2] 88 7b [2] 87 61 [2] 99 7c [2] 9b 7d [2] 80 7b [2] 9c 7c [2] 80 53 }

  condition:
    any of them
}