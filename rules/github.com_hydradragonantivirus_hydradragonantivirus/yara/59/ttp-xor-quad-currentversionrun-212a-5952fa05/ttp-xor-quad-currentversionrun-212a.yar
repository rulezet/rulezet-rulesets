rule TTP_XOR_QUAD_CurrentVersionRun_212a {
  strings:
    $key_212a = { 72 45 [2] 56 4b [2] 7d 67 [2] 53 45 [2] 47 5e [2] 48 44 [2] 56 59 [2] 54 58 [2] 4f 5e [2] 53 59 [2] 4f 76 }

  condition:
    any of them
}