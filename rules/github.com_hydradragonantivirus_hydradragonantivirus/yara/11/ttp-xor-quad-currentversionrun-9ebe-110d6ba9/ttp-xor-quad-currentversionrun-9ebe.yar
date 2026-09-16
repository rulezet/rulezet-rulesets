rule TTP_XOR_QUAD_CurrentVersionRun_9ebe {
  strings:
    $key_9ebe = { cd d1 [2] e9 df [2] c2 f3 [2] ec d1 [2] f8 ca [2] f7 d0 [2] e9 cd [2] eb cc [2] f0 ca [2] ec cd [2] f0 e2 }

  condition:
    any of them
}