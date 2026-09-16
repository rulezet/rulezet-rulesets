rule pcnt_cert {
  meta:
    author = "Etienne Maynier"
    email  = "etienne@citizenlab.ca"

  strings:
    $a = "MIIDWjCCAkICCQCdeJZhGKJakTANBgkqhkiG9w0BAQUFADBvMQswCQYDVQQGEwJV"
    $b = "UzERMA8GA1UECAwITmVicmFza2ExEDAOBgNVBAcMB0xpbmNvbG4xDTALBgNVBAoM"
    $c = "BFBDTlQxDTALBgNVBAsMBFBDTlQxHTAbBgkqhkiG9w0BCQEWDnBjbnRAZ21haWwu"
    $d = "Y29tMB4XDTE4MDEwNjA2MDMyMloXDTI4MDEwNDA2MDMyMlowbzELMAkGA1UEBhMC"
    $e = "VVMxETAPBgNVBAgMCE5lYnJhc2thMRAwDgYDVQQHDAdMaW5jb2xuMQ0wCwYDVQQK"
    $f = "DARQQ05UMQ0wCwYDVQQLDARQQ05UMR0wGwYJKoZIhvcNAQkBFg5wY250QGdtYWls"
    $g = "LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK+ihHezE6jjS2Vl"
    $h = "/rIIQsrczmbjU/4KYDiLiCcrxN0tht6GzL281KGoW13IiQvKILANmx02IAy5tzij"
    $i = "0W9ZvFAIRRYVDpoSU+EyXz4LjHgXvw6VeG9v3HV99iSmphkq7mLYee0EPYP6wSdB"

  condition:
    uint16(0) == 0x5A4D and all of them
}