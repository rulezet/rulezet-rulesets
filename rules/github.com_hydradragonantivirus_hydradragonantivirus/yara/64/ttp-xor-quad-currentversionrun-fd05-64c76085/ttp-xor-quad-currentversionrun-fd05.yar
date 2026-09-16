rule TTP_XOR_QUAD_CurrentVersionRun_fd05 {
  strings:
    $key_fd05 = { ae 6a [2] 8a 64 [2] a1 48 [2] 8f 6a [2] 9b 71 [2] 94 6b [2] 8a 76 [2] 88 77 [2] 93 71 [2] 8f 76 [2] 93 59 }

  condition:
    any of them
}