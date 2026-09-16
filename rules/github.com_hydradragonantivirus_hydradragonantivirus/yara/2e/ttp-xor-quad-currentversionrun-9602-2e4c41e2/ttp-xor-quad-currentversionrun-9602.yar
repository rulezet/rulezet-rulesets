rule TTP_XOR_QUAD_CurrentVersionRun_9602 {
  strings:
    $key_9602 = { c5 6d [2] e1 63 [2] ca 4f [2] e4 6d [2] f0 76 [2] ff 6c [2] e1 71 [2] e3 70 [2] f8 76 [2] e4 71 [2] f8 5e }

  condition:
    any of them
}