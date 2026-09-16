rule cache_mailer {
  meta:
    author = "Brian Laskowski"
    info   = " php mailer script "

  strings:
    $s1 = "if (mail(stripslashes(base64_decode($fr[0]))"

  condition:
    all of them
}