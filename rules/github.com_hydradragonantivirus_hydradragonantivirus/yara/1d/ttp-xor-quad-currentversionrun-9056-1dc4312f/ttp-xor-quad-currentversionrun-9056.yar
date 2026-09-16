rule TTP_XOR_QUAD_CurrentVersionRun_9056 {
  strings:
    $key_9056 = { c3 39 [2] e7 37 [2] cc 1b [2] e2 39 [2] f6 22 [2] f9 38 [2] e7 25 [2] e5 24 [2] fe 22 [2] e2 25 [2] fe 0a }

  condition:
    any of them
}