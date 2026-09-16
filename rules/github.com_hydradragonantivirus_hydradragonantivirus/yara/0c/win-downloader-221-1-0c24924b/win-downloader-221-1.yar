rule Win_Downloader_221_1
{
strings:
	$a0 = { d8a7e626f8f43e3cdc0177ee1e3eecb09222d6fe89cc3a374d0532b99416a90cd06d42e64996b2d5bae95db2ecebbbfa2db91f8ac4e78ec75d90c74f1c89eb00d21f56476a0e49569a35afef1b0d6169f7e44998a0 }


condition:
	$a0
}