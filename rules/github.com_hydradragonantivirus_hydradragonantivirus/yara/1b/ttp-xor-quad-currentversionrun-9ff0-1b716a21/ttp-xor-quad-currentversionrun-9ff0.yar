rule TTP_XOR_QUAD_CurrentVersionRun_9ff0 {
  strings:
    $key_9ff0 = { cc 9f [2] e8 91 [2] c3 bd [2] ed 9f [2] f9 84 [2] f6 9e [2] e8 83 [2] ea 82 [2] f1 84 [2] ed 83 [2] f1 ac }

  condition:
    any of them
}