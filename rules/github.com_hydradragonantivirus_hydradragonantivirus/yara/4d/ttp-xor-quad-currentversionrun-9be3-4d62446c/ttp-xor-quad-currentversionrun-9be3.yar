rule TTP_XOR_QUAD_CurrentVersionRun_9be3 {
  strings:
    $key_9be3 = { c8 8c [2] ec 82 [2] c7 ae [2] e9 8c [2] fd 97 [2] f2 8d [2] ec 90 [2] ee 91 [2] f5 97 [2] e9 90 [2] f5 bf }

  condition:
    any of them
}