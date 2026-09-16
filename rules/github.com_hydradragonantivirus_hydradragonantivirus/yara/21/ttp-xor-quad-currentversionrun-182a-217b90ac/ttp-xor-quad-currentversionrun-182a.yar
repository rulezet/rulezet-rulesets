rule TTP_XOR_QUAD_CurrentVersionRun_182a {
  strings:
    $key_182a = { 4b 45 [2] 6f 4b [2] 44 67 [2] 6a 45 [2] 7e 5e [2] 71 44 [2] 6f 59 [2] 6d 58 [2] 76 5e [2] 6a 59 [2] 76 76 }

  condition:
    any of them
}