rule Orca_Puppet
{
meta:
	id = "s2PjsAb7LnZvcnL4CcpTL"
	fingerprint = "v1_sha256_f57fd21665cb3e75a5f56b3d3c5eb00d827bf5b5e96cb79f1cb775b300884837"
	version = "1.0"
	date = "2026-01-19"
	modified = "2026-01-19"
	status = "RELEASED"
	sharing = "TLP:CLEAR"
	source = "BARTBLAZE"
	author = "@bartblaze"
	description = "Identifies OrcaC2, a multi-functional C&C framework based on WebSocket encrypted communication."
	category = "MALWARE"
	malware_type = "HACKTOOL"
	reference = "https://github.com/Ptkatz/OrcaC2"
	tool = "ORCAC2"

strings:
	$ = "C:/Users/blood/Desktop/AAA/OrcaC2/"
	$ = "Orca_Puppet/pkg/"
	$ = "Orca_Puppet/cli/"
	$ = "Orca_Puppet/stager"
	$ = "OrcaC2_0H" fullword
	
condition:
	any of them
}