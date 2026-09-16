rule TTP_XOR_QUAD_CurrentVersionRun_eb2a {
  strings:
    $key_eb2a = { b8 45 [2] 9c 4b [2] b7 67 [2] 99 45 [2] 8d 5e [2] 82 44 [2] 9c 59 [2] 9e 58 [2] 85 5e [2] 99 59 [2] 85 76 }

  condition:
    any of them
}